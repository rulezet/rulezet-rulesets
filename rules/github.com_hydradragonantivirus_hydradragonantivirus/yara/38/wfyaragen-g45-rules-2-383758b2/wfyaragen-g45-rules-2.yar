rule WFYARAGEN_G45_rules_2 {
  meta:
    description = "Catches generic backdoor - setting an option"

  strings:
    $re = /\$home_cwd\s*=\s*@getcwd\s*\(\s*\)\s*;\s*if\s*\(\s*isset\s*\(\s*\$_POST\s*\[\s*['"]\w{1,10}['"]\s*\]\s*\)\s*\)\s*@chdir\s*\(\s*\$_POST\s*\[\s*['"]\w{1,10}['"]\s*\]\s*\)\s*;\s*\$cwd\s*=\s*@getcwd\s*\(\s*\)\s*;\s*if\s*\(\s*\$os\s*==\s*['"]win['"]\s*\)/ nocase

  condition:
    $re
}