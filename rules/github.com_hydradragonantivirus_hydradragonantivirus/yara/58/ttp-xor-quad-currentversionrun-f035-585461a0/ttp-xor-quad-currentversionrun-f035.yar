rule TTP_XOR_QUAD_CurrentVersionRun_f035 {
  strings:
    $key_f035 = { a3 5a [2] 87 54 [2] ac 78 [2] 82 5a [2] 96 41 [2] 99 5b [2] 87 46 [2] 85 47 [2] 9e 41 [2] 82 46 [2] 9e 69 }

  condition:
    any of them
}