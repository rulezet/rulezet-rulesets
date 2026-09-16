rule warning_EPS_xor_exec {
  meta:
    is_exploit = false
    is_warning = true
    is_feature = true
    rank       = 5
    revision   = "1"
    date       = "May 11 2017"
    author     = "@tylabs"
    release    = "lite"
    copyright  = "QuickSand.io (c) Copyright 2017. All rights reserved."
    tlp        = "green"
    sigtype    = "cryptam_exploit"
    desc       = "EPS obfuscation using xor and exec"

  strings:
    $h1 = "%!PS-Adobe-" nocase
    $s1 = "mod get xor put"
    $s2 = "exec quit"

  condition:
    $h1 at 0 and all of ($s*)
}