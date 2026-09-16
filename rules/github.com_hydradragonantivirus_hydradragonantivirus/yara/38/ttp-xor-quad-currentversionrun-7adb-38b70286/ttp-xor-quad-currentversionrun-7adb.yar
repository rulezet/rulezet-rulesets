rule TTP_XOR_QUAD_CurrentVersionRun_7adb {
  strings:
    $key_7adb = { 29 b4 [2] 0d ba [2] 26 96 [2] 08 b4 [2] 1c af [2] 13 b5 [2] 0d a8 [2] 0f a9 [2] 14 af [2] 08 a8 [2] 14 87 }

  condition:
    any of them
}