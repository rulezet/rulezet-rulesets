rule _20160921_5e3ac68b2242250176f3300039d176f6_20160921_8471da3d602d_2991 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash2       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash3       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "ction f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return" ascii
    $s2 = "){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";}" ascii
    $s3 = "\"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(func" ascii
    $s4 = "})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f00" ascii
    $s5 = "tion f000(){return \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s6 = "n f000(){return \"Br\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Z" ascii
    $s7 = "turn \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}