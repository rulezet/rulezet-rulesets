rule _20160921_04e35734989b05b680234592aacc01ad_20160921_0ae28061d65a_4205 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_4bd4835c5d72bd0171c38863a7d5fba6.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_82c6439487239a08e403c18f347e12e6.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js, 20160921_8f9d19bbb031c21665ebbafad8d5ab55.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash3       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash4       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash5       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash6       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash7       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash8       = "34fcd9c1543d39dfd57d9c09da7c6123934388bbc0bf645db2a4dae174f514cc"
    hash9       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash10      = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash11      = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash12      = "db301ab72cd18ad4198865983d8e64e1840325c04d40cacaa8f5e2097faee094"
    hash13      = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"
    hash14      = "b4039cc962a684523fe76faba20cbc27d33e0e6b0c86feb67e04127cf37a2fc4"
    hash15      = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash16      = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"
    hash17      = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"
    hash18      = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1 = "unction fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){re" ascii
    $s2 = "){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(" ascii
    $s3 = "UXf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(functio" ascii
    $s4 = "ion fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s5 = "ck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}