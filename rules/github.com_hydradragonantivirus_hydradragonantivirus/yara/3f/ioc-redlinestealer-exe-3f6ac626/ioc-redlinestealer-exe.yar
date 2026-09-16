import "hash"
rule IOC_REDLINESTEALER_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_REDLINESTEALER_LAB"
    date_IOC   = "2023-11-14 04:33:16"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "REDLINESTEALER"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "ba87c237b03a3a5a54273ccded35d16559f33678a76f05ce856389e207b68046" or
    hash.sha256(0, filesize) == "5f718ca24fcd480d7daad2d100dd55b7491c8704765b1fefc09884b3e1f31ebe" or
    hash.sha256(0, filesize) == "154977c01029dd441484b65ac21a15ecd7f6144d48eccc5b2ecb67a56bf7cd90" or
    hash.sha256(0, filesize) == "16a1c64a64c741f354cfa13e4640e2c10917a6968dc0ac075d0c3c13270a87cf" or
    hash.sha256(0, filesize) == "195256a242e1a4f2a1833194d97951ebb74ac0091b0cd6be50a3e2f01691b421" or
    hash.sha256(0, filesize) == "0bbc5d27d984dd680feb23e3aeae57f7139953d3efb11926b65952b5f664cf10" or
    hash.sha256(0, filesize) == "26bb80ea94240a03b487cb1f62459d06a8ba4f9abc207cb5372a49609bfbabcf" or
    hash.sha256(0, filesize) == "743754530bf3cdcf57d1f00030b109ffce1431d59d3bb0db3af2c45a57523928" or
    hash.sha256(0, filesize) == "d2c19e15edee855176d5dbf18b19833779e009573573b419c0513e3cf82e6650" or
    hash.sha256(0, filesize) == "6965c5ea91cea03b9a1204a762277a3ee3f4f89f02f2fea0599b6db6ea49e6f0" or
    hash.sha256(0, filesize) == "23943b3d6938425abb71b4e82e9b8d3e93979091c175128c9f167dfc67118968" or
    hash.sha256(0, filesize) == "f7c6af19e272f9017f27afa2699e68759a231edfcb1386f854121257d405e167" or
    hash.sha256(0, filesize) == "90c9d40878861fb8a41fe65b46aab0a2a7153866619beb2efa2be92d71ffd240" or
    hash.sha256(0, filesize) == "e3ba3128521529aa94345e7afbff46bee7a4c38eadce2e4f3a931afb22fad365" or
    hash.sha256(0, filesize) == "7db04ddb55518c98493c17e533c6607d28a10d5385aa236d9a84a10670c49574" or
    hash.sha256(0, filesize) == "cdd3fc19ff6129cd6a4ce32c48a2eceb0ed91e3f129e6f660bcfcebeac1296bc" or
    hash.sha256(0, filesize) == "93851cdb575d5ef907a563962037853c8a59f77a8912db9ec637ef33a9d608b7" or
    hash.sha256(0, filesize) == "fe3b975cd1b89dcd4ec203a5c74a6b612a2df2df4f200d40b5bd2efd9ab5d73f" or
    hash.sha256(0, filesize) == "929e07936c124aca9a998c29cc6c75e91ec2f0f6a45acdc4b5d55ebcd453292c" or
    hash.sha256(0, filesize) == "e69fa17979f4dc03a37fbe37f92d686092271a6d610ae3d31d59d52441dd812a" or
    hash.sha256(0, filesize) == "d2df430d281ad78bc0690d63df9896fe195e2df53f2e9182c6f459094f70aa45" or
    hash.sha256(0, filesize) == "c9c5798e7a3d4bd33f48a62c21591a50d890d25d509aa359798720ea4ba3fb14" or
    hash.sha256(0, filesize) == "1114fd06909159c440fadc3bdb3ce6a5fc1c2ac3bcac48dc3a6b4402eb245fcf" or
    hash.sha256(0, filesize) == "4f3d3b8e805a031fe8eeb47dca418fcbcade5d0190ecdee8930e942c9b4028ea" or
    hash.sha256(0, filesize) == "0965997e1ccaef06f3bb54b93e0e7b3723bb9d99a0944f5550dc5c69cc9c42b8" or
    hash.sha256(0, filesize) == "a3cc4fff4aac80dd379ae09712229eff389c1172d888180dbce61715965f4885" or
    hash.sha256(0, filesize) == "dd49ae56ccd5824fe4f6b62ed6b3b3466a40e56163c23adee63b9b26d96b09c5" or
    hash.sha256(0, filesize) == "fdad89fe9db1c6caa09660a2abd2a99e73a8f442dec417ff49b22614057c74ca" or
    hash.sha256(0, filesize) == "6e627ca700a4794c9e46a849daed709312bacf1587109607e2f6c5eebb8a2598" or
    hash.sha256(0, filesize) == "8e658be1287f69327c68a575863888918e1ca90e2bd09247170a81af6b3cd34b" or
    hash.sha256(0, filesize) == "07df78604d9da2c127e1ab1b9dcf77cece0d2ba536746a7615c65d6689debeb8" or
    hash.sha256(0, filesize) == "3e5d50f9256e94ff3a0e33bd30c01998a5cf299daf96808747729fb72650eab1" or
    hash.sha256(0, filesize) == "2bccfd325ef0ae6b5522b4be977a4d25f81b42a2240c8a072773ef6ed6517900" or
    hash.sha256(0, filesize) == "b4fc50feb3200e9f998dbb7b89dc252220c913c039624fb599aaaab413ede44e" or
    hash.sha256(0, filesize) == "bbe4b4a0aab75cfdeb067064f73e05d793d699247ecd0ec93ef576cc115baca9" or
    hash.sha256(0, filesize) == "19034212e12ba3c5087a21641121a70f9067a5621e5d03761e91aca63d20d993" or
    hash.sha256(0, filesize) == "443fecbe6006903b09fa090230b790dd28249f5b17927c4989bc8c8eaad3ea3d" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}