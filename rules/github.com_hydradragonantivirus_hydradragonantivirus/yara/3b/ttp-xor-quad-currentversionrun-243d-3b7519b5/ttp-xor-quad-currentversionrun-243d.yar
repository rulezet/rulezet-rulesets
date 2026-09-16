rule TTP_XOR_QUAD_CurrentVersionRun_243d {
  strings:
    $key_243d = { 77 52 [2] 53 5c [2] 78 70 [2] 56 52 [2] 42 49 [2] 4d 53 [2] 53 4e [2] 51 4f [2] 4a 49 [2] 56 4e [2] 4a 61 }

  condition:
    any of them
}