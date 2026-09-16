rule TTP_XOR_QUAD_CurrentVersionRun_05f0 {
  strings:
    $key_05f0 = { 56 9f [2] 72 91 [2] 59 bd [2] 77 9f [2] 63 84 [2] 6c 9e [2] 72 83 [2] 70 82 [2] 6b 84 [2] 77 83 [2] 6b ac }

  condition:
    any of them
}