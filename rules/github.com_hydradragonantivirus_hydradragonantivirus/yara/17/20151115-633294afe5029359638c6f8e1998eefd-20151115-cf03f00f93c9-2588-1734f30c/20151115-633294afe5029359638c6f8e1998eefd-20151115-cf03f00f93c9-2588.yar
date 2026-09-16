rule _20151115_633294afe5029359638c6f8e1998eefd_20151115_cf03f00f93c9_2588 {
  meta:
    description = "datamaliciousorder - from files 20151115_633294afe5029359638c6f8e1998eefd.js, 20151115_cf03f00f93c979aff018693125f6d094.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f05332c426fc577cdebf418e0e2aa203a3796739bfcfbd8e9706b188928049ad"
    hash2       = "2aeed9cdec3568a66742fd66d2fc82964ea8a8222737ca8f9d80ef40e5cdd5a3"

  strings:
    $s1 = "){return ' }; }; ';};function a0(){return '=3; n++';};function m7(){return '.saveTo';};function l4(){return 'eateOb';};function " ascii
    $s2 = "var str=\"5552525E0D0A020B24060108130B0B000A1D4A070B095E3C5E13051713054A070B4A110F5E17555E555050535152565555575E55\";function s6" ascii
    $s3 = "turn 'TP\"); v';};function r7(){return 'pen(); ';};function v8(){return 'omCharC';};function z1(){return 'ript.Cr';};function v7" ascii
    $s4 = "{return 't sam';};function t6(){return 'eak; ';};function h6(){return 'n = 0;';};function v9(){return 'llery';};function x5(){re" ascii
    $s5 = "){return 'ar ws ';};function u6(){return 'er/?id';};function b9(){return 'ite(xo.';};function m6(){return 'e = 1';};function v1(" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}