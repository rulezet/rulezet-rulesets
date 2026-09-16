rule TTP_XOR_QUAD_CurrentVersionRun_f821 {
  strings:
    $key_f821 = { ab 4e [2] 8f 40 [2] a4 6c [2] 8a 4e [2] 9e 55 [2] 91 4f [2] 8f 52 [2] 8d 53 [2] 96 55 [2] 8a 52 [2] 96 7d }

  condition:
    any of them
}