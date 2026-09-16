rule TTP_XOR_QUAD_CurrentVersionRun_f618 {
  strings:
    $key_f618 = { a5 77 [2] 81 79 [2] aa 55 [2] 84 77 [2] 90 6c [2] 9f 76 [2] 81 6b [2] 83 6a [2] 98 6c [2] 84 6b [2] 98 44 }

  condition:
    any of them
}