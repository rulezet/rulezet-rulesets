rule TTP_XOR_QUAD_CurrentVersionRun_62e5 {
  strings:
    $key_62e5 = { 31 8a [2] 15 84 [2] 3e a8 [2] 10 8a [2] 04 91 [2] 0b 8b [2] 15 96 [2] 17 97 [2] 0c 91 [2] 10 96 [2] 0c b9 }

  condition:
    any of them
}