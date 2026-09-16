rule TTP_XOR_QUAD_CurrentVersionRun_5011 {
  strings:
    $key_5011 = { 03 7e [2] 27 70 [2] 0c 5c [2] 22 7e [2] 36 65 [2] 39 7f [2] 27 62 [2] 25 63 [2] 3e 65 [2] 22 62 [2] 3e 4d }

  condition:
    any of them
}