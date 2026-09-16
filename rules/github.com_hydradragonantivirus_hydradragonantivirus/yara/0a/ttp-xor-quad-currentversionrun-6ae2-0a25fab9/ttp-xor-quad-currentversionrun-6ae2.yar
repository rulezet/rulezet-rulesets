rule TTP_XOR_QUAD_CurrentVersionRun_6ae2 {
  strings:
    $key_6ae2 = { 39 8d [2] 1d 83 [2] 36 af [2] 18 8d [2] 0c 96 [2] 03 8c [2] 1d 91 [2] 1f 90 [2] 04 96 [2] 18 91 [2] 04 be }

  condition:
    any of them
}