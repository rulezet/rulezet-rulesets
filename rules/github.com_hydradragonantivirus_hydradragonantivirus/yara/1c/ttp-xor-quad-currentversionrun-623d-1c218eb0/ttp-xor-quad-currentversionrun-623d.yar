rule TTP_XOR_QUAD_CurrentVersionRun_623d {
  strings:
    $key_623d = { 31 52 [2] 15 5c [2] 3e 70 [2] 10 52 [2] 04 49 [2] 0b 53 [2] 15 4e [2] 17 4f [2] 0c 49 [2] 10 4e [2] 0c 61 }

  condition:
    any of them
}