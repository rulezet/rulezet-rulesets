rule TTP_XOR_QUAD_CurrentVersionRun_5771 {
  strings:
    $key_5771 = { 04 1e [2] 20 10 [2] 0b 3c [2] 25 1e [2] 31 05 [2] 3e 1f [2] 20 02 [2] 22 03 [2] 39 05 [2] 25 02 [2] 39 2d }

  condition:
    any of them
}