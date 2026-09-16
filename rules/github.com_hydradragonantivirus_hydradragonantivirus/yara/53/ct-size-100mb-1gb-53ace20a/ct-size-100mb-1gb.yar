rule ct_size_100mb_1gb {
  condition:
    filesize > 100MB and filesize < 1000MB
}