rule TTP_XOR_QUAD_CurrentVersionRun_6a20 {
  strings:
    $key_6a20 = { 39 4f [2] 1d 41 [2] 36 6d [2] 18 4f [2] 0c 54 [2] 03 4e [2] 1d 53 [2] 1f 52 [2] 04 54 [2] 18 53 [2] 04 7c }

  condition:
    any of them
}