rule _20160921_0298568f245d937dde081d505d360a5e_20160921_04a7baf184ab_356 {
  meta:
    description = "datamaliciousorder - from files 20160921_0298568f245d937dde081d505d360a5e.js, 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_0a01ee7cfd6766c586aae7f0cd5ba8ac.js, 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_1664afae318573894e850f85ff412d64.js, 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_21041f3360c455bf09d8b48dda6959f3.js, 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_3b2083afdb57ae7e611f6f42c6787c73.js, 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js, 20160921_9b04118eed50c5e7331c4157a5c4dfc8.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f31455e0194491e66143329dadae1760f33af4219844671541520909cf32d58"
    hash2       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash3       = "ab92df4d278f844bff1f6b011a9c332faae5828bb4324384139b2829693be23b"
    hash4       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash5       = "c41fd157f38d62b8a8b91fe197ee0a409bd6fd7582b976184456d2447110138a"
    hash6       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash7       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash8       = "de559d9fde4fb08962605e84afb3f8e86d21c757f1189b673ed0648e3dd75cd0"
    hash9       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash10      = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash11      = "4c81783a1510b3172e1702365554b0e2000709a4e4217a8970aa381c9b357e36"
    hash12      = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash13      = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"
    hash14      = "fdb29344d617d9ae88ae6d7109bec25567e1c486cbb28c248a65e9f2a678c75d"
    hash15      = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"
    hash16      = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"
    hash17      = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"
    hash18      = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1  = "function fuck(){return \"Xw\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){ret" ascii
    $s2  = "(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(" ascii
    $s3  = "tion fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii
    $s4  = "u\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function " ascii
    $s5  = "),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){r" ascii
    $s6  = "Xf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s7  = "\"Za\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(func" ascii
    $s8  = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})" ascii
    $s9  = ";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Jh\";})(),(function fuck" ascii
    $s10 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"CCb\";})(),(function fu" ascii
    $s11 = "urn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"To\";})(),(fu" ascii
    $s12 = "),(function fuck(){return \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s13 = "(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";" ascii
    $s14 = "})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"To\";})(),(function fuck" ascii
    $s15 = "u\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s16 = "})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(" ascii
    $s17 = "ck(){return \"Xw\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";" ascii
    $s18 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"CCb\";})(),(fu" ascii
    $s19 = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ot\";})" ascii
    $s20 = "(function fuck(){return \"Xw\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}