rule _20160921_334dc22c3620386c4119de547e0c0f38_20160921_9ed8ba5d12b4_4880 {
  meta:
    description = "datamaliciousorder - from files 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_ea3000546b29aee563be9d58318d1857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash2       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"
    hash3       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash4       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"

  strings:
    $s1 = " \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(fun" ascii
    $s2 = "),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){" ascii
    $s3 = "GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(functi" ascii
    $s4 = "on f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"" ascii
    $s5 = "00(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}