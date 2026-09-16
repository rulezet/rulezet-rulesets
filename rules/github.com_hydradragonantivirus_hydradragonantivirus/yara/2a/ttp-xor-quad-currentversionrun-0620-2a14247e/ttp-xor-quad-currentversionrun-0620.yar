rule TTP_XOR_QUAD_CurrentVersionRun_0620 {
  strings:
    $key_0620 = { 55 4f [2] 71 41 [2] 5a 6d [2] 74 4f [2] 60 54 [2] 6f 4e [2] 71 53 [2] 73 52 [2] 68 54 [2] 74 53 [2] 68 7c }

  condition:
    any of them
}