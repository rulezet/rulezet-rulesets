rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_19d073f9fafc_1635 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_21f60aa0eac9b2e1c271920e1ba030bb.js, 20160921_24a000738e40009c8bea0a81a0c09cf4.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_67c50b9dab5bb43a7f01552ab820f46c.js, 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_8843826fc0ae466921b7811b54d8314e.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_c1b40d45f00b78160e529a681e4a3e74.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash3       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash4       = "d62e554404acfef03995a5bdd7d29935f7247fd9707d5ea364fac80fddc940f7"
    hash5       = "f61bde20fd51cb3330f21d75680b7197049050166838d3ae36cae4b7521bfd50"
    hash6       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash7       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash8       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash9       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash10      = "95b498a0f19ae8b7e9793e4cb9042b95bb6ba62738825d4cc0684c4bbb8a3d9d"
    hash11      = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash12      = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"
    hash13      = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash14      = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash15      = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash16      = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash17      = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash18      = "7f60ab751a30586a95b22cfdbd81084844857ca6374ef9bc8bd4cbdb7cd3cdf9"
    hash19      = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash20      = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash21      = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash22      = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash23      = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"
    hash24      = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"
    hash25      = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1  = "})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Lo\";})(),(function f000" ascii
    $s2  = "f000(){return \"MBb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Lp" ascii
    $s3  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){retu" ascii
    $s4  = "tion f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s5  = "urn \"SEo\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(fu" ascii
    $s6  = "Uo\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s7  = "function f000(){return \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s8  = "turn \"Nx\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s9  = "tion f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mc\";})(),(function f000(){return " ascii
    $s10 = "00(){return \"DYx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s11 = "nction f000(){return \"Yz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}