rule TTP_XOR_QUAD_CurrentVersionRun_263a {
  strings:
    $key_263a = { 75 55 [2] 51 5b [2] 7a 77 [2] 54 55 [2] 40 4e [2] 4f 54 [2] 51 49 [2] 53 48 [2] 48 4e [2] 54 49 [2] 48 66 }

  condition:
    any of them
}