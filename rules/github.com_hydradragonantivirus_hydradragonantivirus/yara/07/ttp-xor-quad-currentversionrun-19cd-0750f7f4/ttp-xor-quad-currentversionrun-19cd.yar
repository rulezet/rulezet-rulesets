rule TTP_XOR_QUAD_CurrentVersionRun_19cd {
  strings:
    $key_19cd = { 4a a2 [2] 6e ac [2] 45 80 [2] 6b a2 [2] 7f b9 [2] 70 a3 [2] 6e be [2] 6c bf [2] 77 b9 [2] 6b be [2] 77 91 }

  condition:
    any of them
}