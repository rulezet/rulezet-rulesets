rule TTP_XOR_QUAD_CurrentVersionRun_0eb1 {
  strings:
    $key_0eb1 = { 5d de [2] 79 d0 [2] 52 fc [2] 7c de [2] 68 c5 [2] 67 df [2] 79 c2 [2] 7b c3 [2] 60 c5 [2] 7c c2 [2] 60 ed }

  condition:
    any of them
}