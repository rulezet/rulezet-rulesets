rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_4157 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash4       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash5       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash6       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash7       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash8       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"
    hash9       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1 = ";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function f" ascii
    $s2 = "\"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s3 = "ck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo" ascii
    $s4 = "uck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu" ascii
    $s5 = "urn \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}