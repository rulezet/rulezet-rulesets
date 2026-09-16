rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_85f6e34eb7e2_3922 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"

  strings:
    $s1 = "on f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s2 = "function f000(){return \"QDg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){re" ascii
    $s3 = "tion f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s4 = "eturn \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"TRc\";})()" ascii
    $s5 = "000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\"" ascii
    $s6 = "eturn \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}