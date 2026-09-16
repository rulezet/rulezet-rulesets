rule TTP_XOR_QUAD_CurrentVersionRun_343c {
  strings:
    $key_343c = { 67 53 [2] 43 5d [2] 68 71 [2] 46 53 [2] 52 48 [2] 5d 52 [2] 43 4f [2] 41 4e [2] 5a 48 [2] 46 4f [2] 5a 60 }

  condition:
    any of them
}