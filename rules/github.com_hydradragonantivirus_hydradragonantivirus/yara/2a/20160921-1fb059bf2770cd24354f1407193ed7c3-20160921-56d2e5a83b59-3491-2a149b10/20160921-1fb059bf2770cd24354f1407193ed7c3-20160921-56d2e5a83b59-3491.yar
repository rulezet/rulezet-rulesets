rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_56d2e5a83b59_3491 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash3       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"

  strings:
    $s1 = "(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000()" ascii
    $s2 = "eturn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"BMj\";})()," ascii
    $s3 = "0(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";" ascii
    $s4 = "\"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s5 = "n f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"" ascii
    $s6 = "ction f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}