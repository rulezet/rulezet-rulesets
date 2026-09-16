rule TTP_XOR_QUAD_CurrentVersionRun_f708 {
  strings:
    $key_f708 = { a4 67 [2] 80 69 [2] ab 45 [2] 85 67 [2] 91 7c [2] 9e 66 [2] 80 7b [2] 82 7a [2] 99 7c [2] 85 7b [2] 99 54 }

  condition:
    any of them
}