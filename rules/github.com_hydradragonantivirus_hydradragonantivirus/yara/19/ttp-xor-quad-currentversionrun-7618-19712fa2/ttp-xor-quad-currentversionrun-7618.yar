rule TTP_XOR_QUAD_CurrentVersionRun_7618 {
  strings:
    $key_7618 = { 25 77 [2] 01 79 [2] 2a 55 [2] 04 77 [2] 10 6c [2] 1f 76 [2] 01 6b [2] 03 6a [2] 18 6c [2] 04 6b [2] 18 44 }

  condition:
    any of them
}