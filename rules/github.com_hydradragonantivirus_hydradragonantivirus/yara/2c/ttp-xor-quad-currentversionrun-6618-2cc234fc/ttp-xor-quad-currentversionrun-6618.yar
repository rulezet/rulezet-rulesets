rule TTP_XOR_QUAD_CurrentVersionRun_6618 {
  strings:
    $key_6618 = { 35 77 [2] 11 79 [2] 3a 55 [2] 14 77 [2] 00 6c [2] 0f 76 [2] 11 6b [2] 13 6a [2] 08 6c [2] 14 6b [2] 08 44 }

  condition:
    any of them
}