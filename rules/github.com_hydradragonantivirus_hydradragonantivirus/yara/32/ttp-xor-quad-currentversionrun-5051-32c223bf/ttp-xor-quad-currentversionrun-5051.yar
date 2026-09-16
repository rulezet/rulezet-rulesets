rule TTP_XOR_QUAD_CurrentVersionRun_5051 {
  strings:
    $key_5051 = { 03 3e [2] 27 30 [2] 0c 1c [2] 22 3e [2] 36 25 [2] 39 3f [2] 27 22 [2] 25 23 [2] 3e 25 [2] 22 22 [2] 3e 0d }

  condition:
    any of them
}