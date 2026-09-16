rule TTP_XOR_QUAD_CurrentVersionRun_097c {
  strings:
    $key_097c = { 5a 13 [2] 7e 1d [2] 55 31 [2] 7b 13 [2] 6f 08 [2] 60 12 [2] 7e 0f [2] 7c 0e [2] 67 08 [2] 7b 0f [2] 67 20 }

  condition:
    any of them
}