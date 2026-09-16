rule TTP_XOR_QUAD_CurrentVersionRun_14ef {
  strings:
    $key_14ef = { 47 80 [2] 63 8e [2] 48 a2 [2] 66 80 [2] 72 9b [2] 7d 81 [2] 63 9c [2] 61 9d [2] 7a 9b [2] 66 9c [2] 7a b3 }

  condition:
    any of them
}