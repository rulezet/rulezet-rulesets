rule TTP_XOR_WriteProcessMemory_a17d {
  strings:
    $key_a17d = { f6 0f [2] c4 2d [2] c2 18 [2] ec 18 [2] d3 04 }

  condition:
    any of them
}