rule Spam_PHP_WPVCD_ContentInjection {
  meta:
    description = "Content injection script associated with WP-VCD."

  strings:
    $re = /\$ip\s*=\s*\@file_get_contents\s*\(\s*ABSPATH\s*\.\s*['"]wp\-includes\/wp\-feed\.php['"]/ nocase

  condition:
    $re
}