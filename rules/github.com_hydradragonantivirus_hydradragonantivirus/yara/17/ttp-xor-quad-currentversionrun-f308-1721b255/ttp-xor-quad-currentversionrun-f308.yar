rule TTP_XOR_QUAD_CurrentVersionRun_f308 {
  strings:
    $key_f308 = { a0 67 [2] 84 69 [2] af 45 [2] 81 67 [2] 95 7c [2] 9a 66 [2] 84 7b [2] 86 7a [2] 9d 7c [2] 81 7b [2] 9d 54 }

  condition:
    any of them
}