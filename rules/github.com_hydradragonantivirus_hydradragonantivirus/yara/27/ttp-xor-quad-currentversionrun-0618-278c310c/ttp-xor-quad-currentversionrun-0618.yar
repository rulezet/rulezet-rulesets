rule TTP_XOR_QUAD_CurrentVersionRun_0618 {
  strings:
    $key_0618 = { 55 77 [2] 71 79 [2] 5a 55 [2] 74 77 [2] 60 6c [2] 6f 76 [2] 71 6b [2] 73 6a [2] 68 6c [2] 74 6b [2] 68 44 }

  condition:
    any of them
}