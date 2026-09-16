rule TTP_XOR_QUAD_CurrentVersionRun_f816 {
  strings:
    $key_f816 = { ab 79 [2] 8f 77 [2] a4 5b [2] 8a 79 [2] 9e 62 [2] 91 78 [2] 8f 65 [2] 8d 64 [2] 96 62 [2] 8a 65 [2] 96 4a }

  condition:
    any of them
}