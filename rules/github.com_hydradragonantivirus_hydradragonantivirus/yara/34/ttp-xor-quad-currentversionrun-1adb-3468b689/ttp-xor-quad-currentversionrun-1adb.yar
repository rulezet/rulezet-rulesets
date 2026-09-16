rule TTP_XOR_QUAD_CurrentVersionRun_1adb {
  strings:
    $key_1adb = { 49 b4 [2] 6d ba [2] 46 96 [2] 68 b4 [2] 7c af [2] 73 b5 [2] 6d a8 [2] 6f a9 [2] 74 af [2] 68 a8 [2] 74 87 }

  condition:
    any of them
}