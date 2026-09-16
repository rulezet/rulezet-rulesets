rule WFYARAGEN_G4304_rules_1 {
  meta:
    description = "htaccess rule used to limit access to pages"

  strings:
    $re = /RewriteCond \%\\\{HTTP_USER_AGENT\\\}\!en\.support\.wordpress\.com\s+RewriteRule \.\* \- \[R=404\]/ nocase

  condition:
    $re
}