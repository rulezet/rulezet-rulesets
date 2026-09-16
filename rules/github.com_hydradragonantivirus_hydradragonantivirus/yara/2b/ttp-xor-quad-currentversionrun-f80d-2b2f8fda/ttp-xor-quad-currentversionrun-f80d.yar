rule TTP_XOR_QUAD_CurrentVersionRun_f80d {
  strings:
    $key_f80d = { ab 62 [2] 8f 6c [2] a4 40 [2] 8a 62 [2] 9e 79 [2] 91 63 [2] 8f 7e [2] 8d 7f [2] 96 79 [2] 8a 7e [2] 96 51 }

  condition:
    any of them
}