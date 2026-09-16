rule TTP_XOR_QUAD_CurrentVersionRun_2adb {
  strings:
    $key_2adb = { 79 b4 [2] 5d ba [2] 76 96 [2] 58 b4 [2] 4c af [2] 43 b5 [2] 5d a8 [2] 5f a9 [2] 44 af [2] 58 a8 [2] 44 87 }

  condition:
    any of them
}