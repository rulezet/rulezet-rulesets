rule TTP_XOR_QUAD_CurrentVersionRun_2618 {
  strings:
    $key_2618 = { 75 77 [2] 51 79 [2] 7a 55 [2] 54 77 [2] 40 6c [2] 4f 76 [2] 51 6b [2] 53 6a [2] 48 6c [2] 54 6b [2] 48 44 }

  condition:
    any of them
}