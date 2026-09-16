rule TTP_XOR_QUAD_CurrentVersionRun_f83d {
  strings:
    $key_f83d = { ab 52 [2] 8f 5c [2] a4 70 [2] 8a 52 [2] 9e 49 [2] 91 53 [2] 8f 4e [2] 8d 4f [2] 96 49 [2] 8a 4e [2] 96 61 }

  condition:
    any of them
}