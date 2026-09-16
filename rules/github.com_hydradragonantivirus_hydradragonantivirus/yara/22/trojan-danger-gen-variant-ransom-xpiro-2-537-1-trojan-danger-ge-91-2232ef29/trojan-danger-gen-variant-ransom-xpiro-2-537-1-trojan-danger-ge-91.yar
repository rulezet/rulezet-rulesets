import "pe"
rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_537_1_Trojan_Danger_Ge_91 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_537_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_132_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_140_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_17_1.vir, Trojan.Danger_Generic.Dacic.1A7FA519.A.2D3D82A8_13_1.vir, Trojan.Danger_Generic.Dacic.1A7FA519.A.2D3D82A8_6_1.vir, Trojan.Danger_Trojan.GenericKD.67064203_12_1.vir, Trojan.Danger_Trojan.GenericKD.67064203_18_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_173_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_25_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_314_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_373_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_420_1.vir, Trojan.Danger_Trojan.GenericKD.67166905_78_1.vir, Trojan.Danger_Trojan.GenericKD.72304918_212_1.vir, Trojan.Danger_Trojan.GenericKD.72304918_223_1.vir, Trojan.Danger_Trojan.GenericKD.72304918_83_1.vir, Trojan.Danger_Trojan.GenericKD.72597336_15_1.vir, Trojan.Danger_Trojan.GenericKD.72597336_42.vir, Virus.Danger_Gen.Trojan.ShellObject.juZ@aKo42Jj.vir, Virus.Danger_Gen.Trojan.ShellObject.juZ@aKo42Jj_1.vir, Virus.Danger_Gen.Trojan.ShellObject.KuZ@aKo42Jj.vir, Virus.Danger_Gen.Trojan.ShellObject.puZ@aKo42Jj.vir, Virus.Danger_Trojan.GenericKDZ.103285_50.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_10.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_11.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_12.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_13.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_14.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_15.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_16.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_17.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_18.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.juZ@aKo42Jj_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_10.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_11.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_12.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_13.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_14.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_10.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_11.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.puZ@aKo42Jj_9.vir, Virus.Hijack_Gen.Trojan.ShellObject.WuZ@aKo42Jj.vir, Virus.Hijack_Gen.Trojan.ShellObject.WuZ@aKo42Jj_1.vir, Virus.Hijack_Trojan.GenericKDZ.103285_121.vir, Virus.Hijack_Trojan.GenericKDZ.103285_157.vir, Virus.Hijack_Trojan.GenericKDZ.103285_181.vir, Virus.Hijack_Trojan.GenericKDZ.103285_220.vir, Virus.Hijack_Trojan.GenericKDZ.103285_262.vir, Virus.Hijack_Trojan.GenericKDZ.103285_310.vir, Virus.Hijack_Trojan.GenericKDZ.103285_368.vir, Virus.Hijack_Trojan.GenericKDZ.103285_387.vir, Virus.Hijack_Trojan.GenericKDZ.103285_412.vir, Virus.Hijack_Trojan.GenericKDZ.103285_438.vir, Virus.Hijack_Trojan.GenericKDZ.103285_486.vir, Virus.Hijack_Trojan.GenericKDZ.103285_503.vir, Virus.Hijack_Trojan.GenericKDZ.103285_54.vir, Virus.Hijack_Trojan.GenericKDZ.103285_573.vir, Virus.Hijack_Trojan.GenericKDZ.103285_595.vir, Virus.Hijack_Trojan.GenericKDZ.103285_61.vir, Virus.Hijack_Trojan.GenericKDZ.103285_610.vir, Virus.Hijack_Trojan.GenericKDZ.103285_627.vir, Virus.Hijack_Trojan.GenericKDZ.103285_656.vir, Virus.Hijack_Trojan.GenericKDZ.103285_703.vir, Virus.Hijack_Trojan.GenericKDZ.103285_712.vir, Virus.Hijack_Trojan.GenericKDZ.103285_723.vir, Virus.Hijack_Trojan.GenericKDZ.103285_727.vir, Virus.Hijack_Trojan.GenericKDZ.103285_73.vir, Virus.Hijack_Trojan.GenericKDZ.103285_740.vir, Virus.Hijack_Trojan.GenericKDZ.103285_753.vir, Virus.Hijack_Trojan.GenericKDZ.103285_770.vir, Virus.Hijack_Trojan.GenericKDZ.103285_782.vir, Virus.Hijack_Trojan.GenericKDZ.103285_788.vir, Virus.Hijack_Trojan.GenericKDZ.103285_820.vir, Virus.Hijack_Trojan.GenericKDZ.103285_84.vir, Virus.Hijack_Trojan.GenericKDZ.103285_859.vir, Virus.Hijack_Trojan.GenericKDZ.103285_93.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "213a9788c52ddd5521986de34768c51faa56e60d7dca50d42cf4839fefa1dfe4"
    hash2       = "b8e11cb443686791d0998518b32d9bbaeecf555e53749791f016d8664b7e3677"
    hash3       = "9381f91671a894791fe85ce977bf38aea3808e6981da63cb418e93dc918bce44"
    hash4       = "1beb88648522c0816b68b02d6e64862f813e8afc3b26c4e3b85c649c7599c9ba"
    hash5       = "754f96060d535b74051d5f05d8ce0bed3d0813cf4d2e283318cc15f0d353dd11"
    hash6       = "ea2812f787ab252349f355633157cb2b062eabff10368860a354dca22ee8d664"
    hash7       = "e7c407cb7e862d53ff2f773e936a46ad68b12b7f7595f8b0afeeab7452b9a039"
    hash8       = "d9d520a31cdc9bfd975f0486ab911e9a1c27112ce0f254ef9e89bc78ecaf312a"
    hash9       = "0edc17723fb9e2d5ac5b68c98b0db95041bf97152ce7b6de88af96842472bc4a"
    hash10      = "08cf49078844c5c05b9275f44267aea1a187bfe60702ecb7ca96b91c653ee3a1"
    hash11      = "f01b65923a9d4bc8d79e07c0fd853595a6968c54ab7e891fb800a5739cee227b"
    hash12      = "0ebbbe49e0731e9a3858751a84684d9cc33df503fff6aeccde80433edae9b0d8"
    hash13      = "cb2fecb2bb3ac0c8b367352e2b246de03b045d1a2e1b3f8b9fbef7c15965355e"
    hash14      = "0e2c4da8bdea6aa87b81a4deaa1a869ec692608054ed50e0f67629f0afd8a005"
    hash15      = "e5881207f5c92f84fa2c7f429f7bddecee88e3b08f3b4cb75ae68d70e26e006e"
    hash16      = "c9cb1b1dd348300b56df90ef5aa6709af47c677360491c3990ee124a57320c11"
    hash17      = "de9c46ecc8920c894d5dfc42f13f6fa4218554d274ce7beb420c74bc66f36428"
    hash18      = "a19c820fb1d90391a1c43551c51f11fd53281dfeffcd3791ca18fcb7ffd51035"
    hash19      = "8817d4adb0340236f833bc14d2e9426fdac2f6fb506f272d7e550e36e2e373cb"
    hash20      = "ed7d99fab4f0a686801ffd8e550ff7b2b6b2707fc9a4d1a21bd705dab7bcd5e7"
    hash21      = "4815bad1a2baa58c0427594119c49601831c02c7ae2b12046d7c749a1b9e01d6"
    hash22      = "ea7819ad3567a53ed5d6afee7b0a417f0eff0472f19dba87dca80dd5f8a55e88"
    hash23      = "0c287b856134167d4d82e272237cf752854b7d98f75d6b0583212175703bbe41"
    hash24      = "03d6fbadfd3fbba96b0dc617963398235ce9eb807be2d6eea820a219d8973456"
    hash25      = "7c9561cbaccae387a1ce253d54cb3ebbed3f10b5476c67d4044a7bb9be458ba4"
    hash26      = "a5ce7206fa5f55e7165382df84be44903196eb735a5ee3c55f41201e78d475db"
    hash27      = "0ada67636d2f9454da02e8182bbff58dee7090abd054cffcdc987cae9f656cf6"
    hash28      = "4dbcf40ab6c16368baa6a8b68cd819aec11468feff385043e471a872ab84ef6b"
    hash29      = "15384cd22f37e121c44dcb921dbcebc53d1a9f03e6fbbabcadfb0840c1129bf9"
    hash30      = "000c59ed1b547adc971acb49671de419c24dbb0ee0329fb3fd94d840fed37a95"
    hash31      = "16fddb35ea4839b5057955b44a0d7c66642fed6a199fb17d43c3a7d8803737ff"
    hash32      = "a407cd97c4a5901e839fafc9570c50a3a06a4c01fd87ceb7dab773158c64dd37"
    hash33      = "77f1f039501b772446a96f463d929b675c2dffade64054efc4e151757a0d3695"
    hash34      = "0b244a6315125dc8b2d069e8365f78e955a1c30ac9354ce777f394db06e97052"
    hash35      = "8e94775cf9cca0691690e04007d09409664e7a7a48c27d18698eb6cfd3bbe7a2"
    hash36      = "619f401cbd98d4a13a3495244ad8ad99b07ae8bb6bc16f2fc48627a7d59f6ca9"
    hash37      = "b306b508eeeeaa9c03a1571304d45316a8afd1c1a7c504a68c13680c12a5f64b"
    hash38      = "2608326a0ce3b47751c114c89479971c7c4635a23ce76481b369a8083fc46acf"
    hash39      = "91421388b5bdba8c9a153cf725d46924342e0a38c408df1919db14b19e743c48"
    hash40      = "e621d9345e5b2630eda945cc9109d2519e23b64ab552b9ee5424c80fe1d9127c"
    hash41      = "0c77e0e5b20ef5f2d328710ed6790a9c7d14718cb3c7aa334cb3c135b5b8fc49"
    hash42      = "4eb204810ed2762dced0bc6343e4be5dcc07a4e78a344ca7168bcc92be2ecbf9"
    hash43      = "5c903a742a1a184b1e6a0e18b206aa3b991814aef328dc675c6722bc9925b155"
    hash44      = "f76f79135529bf75baad6843e8b256c46524799d6c7c7b5490e02d09337ce5ba"
    hash45      = "cd33b62756c72ad1040804e5992885e0902b03d65a3be80d07aec9839c18f75b"
    hash46      = "3572fbcb1cb8510aa3f68e53b39671baa2dfcd3c4cab7ba32b60c322c021dc6e"
    hash47      = "b30ea693af0b5d94c2a7c848c686ade9272f8b847fd8bf2756f9aef854935de7"
    hash48      = "bcb66d6c3363da65e8a6ab8d9c93597195a6512d8c6a01882d271e771828e7a5"
    hash49      = "eb3c7c1e3bbec9a98da3cff15a0c2e00371dd0ad3ba79096aab9a3fb5c04cc8a"
    hash50      = "f4234e6982c6d8e484c50aa0d8ece6422688d5071d62a5e58bd94cdc90b5c0bf"
    hash51      = "38e78f29e586f7faf50f4de85fd2613fae9cc1fcd446beb646f8b2ae2136ea5a"
    hash52      = "7c9e30586fe34935e5cba1bf59eb446e0155c9d1c154acc92cbbf1863538ea3c"
    hash53      = "a22e833fd93ef904614e5a211d7aa916a82d6693c620c2cad5d75bc87d4b11aa"
    hash54      = "0e77f688de08b23ba3eb0cac19d38a8cdc9c66af32677063cd2a9f7d6afbd1da"
    hash55      = "00d1f42c3b531e97efa60663a1699dafb0f64a4cbab1140f6558564f12c436f9"
    hash56      = "6b1828617ed212040c9735e578c72bce33b0e399ad1076d442592922de388f90"
    hash57      = "8ec8325110d0c5f6b4a0a055d37a62d2df6323b46c392a5ceb089eb0b11f0190"
    hash58      = "cb0f4cbeefd4bd573b0c52fb1a3bf91ac1dafa413f0ffb267c4750935890bfac"
    hash59      = "270973fa35bbb726f1c85354d1f26f90c5be5cf98a47ba1f1720001e100cd6e8"
    hash60      = "59727d17058eb191e8dc2b363298ac2fb3a374948b2dcd0d3a836865b63b12d8"
    hash61      = "5fc1ff16adf53d5993e7f016e056261ea0b0ddef70382d70f3197defecb11a7d"
    hash62      = "607dba1e9b9ed889ad456c8ff28f220654855f5bc94530f8d70cfd52ccfe507a"
    hash63      = "e8aa64a6bff1def932939c4a031eadf703dafebf50b63125784f9ba36e81bd1e"
    hash64      = "658b36b5abfa60b04159cc41464e3c86b2bc51a6f8ecbbfc463d363d28ef6f53"
    hash65      = "fbcff2e3f6aa12406d74b54d8ea5f4e0a530a943be3bf927ab67d14c26e1e067"
    hash66      = "94349b088bf03f798b363bfa86b1c902dfcb879864f7e986355378e12df39970"
    hash67      = "e57d4ec3a82c10bee6ee296422f4149ad375c06aebdc91f8e0636ae36bcc4e77"
    hash68      = "8c8b869401d4159d812836ffc1199520271d60b4e1042537048858a004fd54bd"
    hash69      = "56a0b3147d03ef273b151ae79181289edb60b55bdc099f1a50db70ebd6d764ab"
    hash70      = "172c94556865cd219c4ee8dc48a71751662d96866270555581ad89478502c397"
    hash71      = "3bc2bd8a07b6b3bbfac81a7578c22e4ae2506509d81868414ff49b06168c6bc1"
    hash72      = "016bb17a4eda22002c3641456368e5e10a6d2335f753137d4697fdb065d9e112"
    hash73      = "01526a3efd937802a9e9c582fcacabc0e5575c097557a77a560df6b2fb62455f"
    hash74      = "4fca92a43a63b11a1d5b5b034369dbb670cba56b52a6bd40233cd6861232203d"
    hash75      = "87d1fc4dac732852382e9c883fa5199ad2cec2236afc9cc30525bf9aaeb26f31"
    hash76      = "5691dd50c91bed8b2c2f3242233c29fd6f52ef0675605ce6d2e539d4093c7d45"
    hash77      = "01ea641c583562580801f77ca56a910134bad51e12e2497f2c23bea74555fb92"
    hash78      = "965f309e8c1fa32c8a917d1b94981305d02e15e934cd01e55754291f1c9b936b"
    hash79      = "12bdf8d230051e16ae46a22d279b8c1fabc0956c97d81a2ae786b7d2378e7390"
    hash80      = "8d685ed788defd1c0e921037f7905763e61926bc40855e805b1b941a1a76ace9"
    hash81      = "8cc4b4875701b47de92973e0a3da08a7c9e058c8683eb37044aa208d7cf02b15"
    hash82      = "18892cb0d533c0e9f7c2de37a102c716cd5a1f4e67c35fe7a65d27df1ee096f7"
    hash83      = "e27d4f3aaeb64f39cfb7a8466213ab7a5fb10e8bf5283d98c443152e523bf3a2"
    hash84      = "161064fc491279a561236422759024a2f852d1ef165befc28336a4f6b7dea6df"
    hash85      = "11e7302d9e24da3858cecd427ba631765f941da58ffff4d2ae6f7a8f5a1903e3"
    hash86      = "a4609b3823ada4684baeeeea5d9a65e5efb3d97e9f7092cdfaab39e059010194"
    hash87      = "feea867e313b13919d7c43ce078cb986649c9902dbbaac24b6601471ec151c0c"
    hash88      = "adb7cb0d6650ba0cc247aeb563b3dbc148c37b137a1058abf128ff7fb885897d"
    hash89      = "d7a1f341eff1468abb812609727c67690c4627ca4be54178fbf58ca637d5b127"
    hash90      = "071df07efa3feea3eb577da128f4bb55dec2df3711ecb2ff3b6dd7db25f3ac43"
    hash91      = "571e79f82d18b591a221bed07bc646520b3a4ad2991375479ea42fa4722bd702"
    hash92      = "72d45253634f19dcce39a8f7bcd3e0f8748e644c1c221fbcb5cbc2738b68c401"
    hash93      = "bcf260cb0a4c7228e5217f7685566d359771aed9f3cacc0953033dd3f0bfce26"
    hash94      = "63717cc6b6f9127a1749f2dcbb02b52d472db4b3cbd23e8fac0e9ce75f3e0cfc"
    hash95      = "abc1a5cf28500ce12d64e713c2aa75ab7240175569f739c86056a34260555247"
    hash96      = "155f9e20bd6636c5f3f3e0b25fe42937a7ba13dcb93d07597399d21b7ba51e53"
    hash97      = "334248fabddab21f492487fa52c0c9ad4d265f4e73d7a14ba5e90826b719863b"
    hash98      = "f62bff0ac2874a4580bc728d3e5caaf4b28f0bcb14d5d8b2fa3464da9603b80f"
    hash99      = "26a1843a873d8e6e3c85345b68862ecedca2e3a58c73e47a38d8ec53ee51ab52"
    hash100     = "45c80f807a7b1c77732c3f654142ddc239ea9365ab1f81cd56d9bafe9f906b5c"
    hash101     = "8b5dc0e6c47a361c683d5f9523790f751378008e734be1758d0ff31d4aa728bd"
    hash102     = "d564e852271966fcd83374f2130d4fcce8d17a843d3cf36b73a8ed8b398d004e"
    hash103     = "fb4af998a8f2be7495e7119dee8f3900a6c9643ccdbf134a167cec8b9d18c901"
    hash104     = "953d355b1376069cc5fa250689e92b0f9dbaa7fe42d26d3bd27db2a2963c9870"
    hash105     = "cc8fcd220e03df601aca5884316ed38007063b213acb5da506d78f2cbb3b0fab"

  strings:
    $s1  = "%s(%d): %s ERROR  : [%p] HcmRequest aborted unexpectedly ?????????? size=%d, userData=%p, userDataTag=%s, failedAttempts=%d" fullword ascii
    $s2  = "%s(%d): %s ERROR  : [%p] reached max retry for HTTP send, size=%d, userData=%p, userDataTags=%s, failedAttempts=%d" fullword ascii
    $s3  = "%24s:%5d [%-10s] %-32s| [%p] HcmRequest GREAT SUCCESS!! size=%d, userData=%p, userDataTags=%s, failedAttempts=%d" fullword ascii
    $s4  = "%s(%d): %s WARNING: [%p] HcmRequest aborted for HTTP send, size=%d, userData=%p, userDataTags=%s, failedAttempts=%d" fullword ascii
    $s5  = "%24s:%5d [%-10s] %-32s| Logger[3]: token=%s, source=%s" fullword ascii
    $s6  = "%s(%d): %s ERROR  : [%p] InternetReadFile: %u bytes - buffer too small!" fullword ascii
    $s7  = "%s(%d): %s ERROR  : Failed to send data, stop processing retry queue." fullword ascii
    $s8  = "%24s:%5d [%-10s] %-32s| [EVENTFLOW]: Processed data from offline storage, packed count=%d, buffer size=%d, maxRequestSize=%d, pr" ascii
    $s9  = "%24s:%5d [%-10s] %-32s| [EVENTFLOW]: Processed data from offline storage, packed count=%d, buffer size=%d, maxRequestSize=%d, pr" ascii
    $s10 = "%s(%d): %s ERROR  : %u errors while reading offline storage, previous contents (%u bytes) dropped." fullword ascii
    $s11 = "%s(%d): %s WARNING: [%p] %s %s - request failed!" fullword ascii
    $s12 = "%s(%d): %s WARNING: [%p] HcmRequest Collector-Error=%s, userData=%p" fullword ascii
    $s13 = "%s(%d): %s ERROR  : [%p] connection failed." fullword ascii
    $s14 = "%24s:%5d [%-10s] %-32s| Initialize[2]: tenantToken=%s, configuration=0x%X" fullword ascii
    $s15 = "%24s:%5d [%-10s] %-32s| [%p] HTTP %s %d, error=%d, body size=%d, userData=%p, retryCount=%d, userDataTags=%s" fullword ascii
    $s16 = "%s(%d): %s ERROR  : Decompression failed, error=%u, len=%u, destLen=%u" fullword ascii
    $s17 = "%24s:%5d [%-10s] %-32s| Create Bond Package with Type = %s, Source = %s, Version = %s, DataPackageId = %s, Timestamp = %lld, Sch" ascii
    $s18 = "%s(%d): %s ERROR  : LogManagerImpl constructor failed with error %d" fullword ascii
    $s19 = "%s(%d): %s WARNING: LogSession We don't have session start time" fullword ascii
    $s20 = "%24s:%5d [%-10s] %-32s| ----------------------------------------- [%p] destroying  request handle=%p state=%s ------------------" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26babd76bbb7f9c516a338b0601b4c9f" and (8 of them)
    ) or (all of them)
}