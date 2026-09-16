rule TTP_XOR_QUAD_CurrentVersionRun_383d {
  strings:
    $key_383d = { 6b 52 [2] 4f 5c [2] 64 70 [2] 4a 52 [2] 5e 49 [2] 51 53 [2] 4f 4e [2] 4d 4f [2] 56 49 [2] 4a 4e [2] 56 61 }

  condition:
    any of them
}