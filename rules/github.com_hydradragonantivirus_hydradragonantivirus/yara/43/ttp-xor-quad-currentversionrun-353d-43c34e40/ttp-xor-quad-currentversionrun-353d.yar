rule TTP_XOR_QUAD_CurrentVersionRun_353d {
  strings:
    $key_353d = { 66 52 [2] 42 5c [2] 69 70 [2] 47 52 [2] 53 49 [2] 5c 53 [2] 42 4e [2] 40 4f [2] 5b 49 [2] 47 4e [2] 5b 61 }

  condition:
    any of them
}