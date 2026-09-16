rule emotet_3_index {
  meta:
    description = "PHP - file emotet-3_index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "d5ae3896c986f490edfe2010dad870dba0deb182166d1bd62261ff5ef2c6830d"

  strings:
    $x1  = "class Rst { const PLATFORM_UNKNOWN = 0; const PLATFORM_ANDROID = 1; const PLATFORM_APPLE = 2; const PLATFORM_LINUX = 3; const PL" ascii
    $s2  = "false) { $spc3aced = self::PLATFORM_APPLE; } } } } return $spc3aced; } public function execute() { $sp53dcff = '.' . sha1(basen" fullword ascii
    $s3  = "$_SERVER['QUERY_STRING']) { die($_SERVER['QUERY_STRING']); } $sp0b39f9 = new Rst(); echo $sp0b39f9->execute();" fullword ascii
    $s4  = "->contentName . '\"'); header('Content-Transfer-Encoding: binary'); return gzinflate(base64_decode($this->contentData)); } } if " ascii
    $s5  = "''; $spc3aced = self::PLATFORM_UNKNOWN; if (stripos($sp46a5c8, 'windows') !== false) { $spc3aced = self::PLATFORM_WINDOWS; } el" fullword ascii
    $s6  = "eDDs6EWzC6EeTG09OWxgTG1rcMD/estqlWAeM5SUTqLX7/pYT0hbzrSXtuq6VJfizrxbe++Bms0NElazTruNSapRkqAiTdWbdTYOYUn4otrAtvtpvNTNwLjxZKMBjJbt" ascii
    $s7  = "Dl4Y1urJxMdq064EVuVpmH3tzPPhWPC5zpF4aT1L2DPb2ScjjIEaD1zvmdY711swur9zBktUGA6EEiPqJ8fkT9aa2iAnH0+GjjXkqiigZ916KeyvPotrUnTMseXGZZyS" ascii
    $s8  = "yd/nKvB8cLgpHFQ0HR7L1nFzyXzi5/8LszL7dNpcgcsncKFYBn9imXwCTrH34Fx4bvje+gcsPDiJF/FJfTp0LkXji1j/sCK+kmRd6bT+Q//8KSUzAVXS+ydIEWKJr0oI" ascii
    $s9  = "zYj/Zzf7P0jtzf5/85/auxJ3j//+S/jbirWLjaEPLK27uOzvjfTPlfy/foN8gyBBOK7SirXvNVT+E98vw9/F939Lfovfr8Pv7zx2TbP4zso69zewa6RIEvD7J1uWPseH" ascii
    $s10 = "rwcfcua96REFBl30figUp4MbSKYhXry//7OF0flr8D6E3enPtiWIZREdnlZELBziVXxk9oDyO/XurW0Up0cLKzrPGmNGRqxe+PWaxzN5Xh2msrH5/CGwUVTkm2pQmmow" ascii
    $s11 = "wq5vfmGn8l/o7c3f7S92+3XZq1e782X1R/by4w4bX87jzS/2NVJf7CO228vs5V/3d/7qK7112UtHbafeYe94d/vdXe/+Z/upXft13Ut/l/9dPbTdK/8be/VW6Rt2+vt5" ascii
    $s12 = "nIL3l+FvnOLv5/Hz/O/4vdZ697s4TR7fj8IfFfb+Snr9BvZ+Aj/fwN5fC39k+PtZ/H3+/mr8fCN7P4730+j+frHRvedyY83nm9j7+EyeJveeH21yf7/S5N7Phmb2fgr+" ascii
    $s13 = "6msIcjrsAXn/md+shxL6L9/pX7/+q/f/P/36//L9/38='; private $contentName = 'FT_2K71C4X2ZQ_CN_10102019.doc'; private $contentType = 'a" ascii
    $s14 = "x/eC/E5n1Bhjkqm8fR5KLyf39HnhCwlj2015Xf4IhQlRzTKejD7xpindwNwK6mRuXtr5sgETtKeK+vEg3nQ+qpK/ifyAKQmjBMFmVXLRFUdX7tWH+RGM0uf4p5sh3fIB" ascii
    $s15 = "DsbWaxtspYNOS3GE797ewBNascuboGeXKdmhbNq+1PAeyfL2Sjs1L774swipZ2MLFtDyiopyJiY+czivHo8RUuS9tqHHe6c2Uff7myBvC3PPC9ifPfVDjZ1PBLKV2Bx+" ascii
    $s16 = "+uwMr2m9vnKyqRuzHzIJM6XP32wiaglsxKeh49Ot9iftPrm7ulG3G8zKX/ajAl8/Uhc96K2gwc5Il2f5HY9M5+iIu6Oxsd/qlfLS+/1F6EYla/F4U51iZBfb05h02ylM" ascii
    $s17 = "dqk3KYxhIHEhXnc1gLewCVsRY/wnBZnsvFj3cDvWQEbqCbGzQ86ur2VtXYIu4b36oX4lrxnD1L/dmFnmNR/BI6IbwXMB2WMXL8ylVdmtgPkIaSovWlog+WwZUUg2Zm+2" ascii
    $s18 = "xD0sQo8FTpbk5olOVVcCq+spSX0VxwUj3zBUKuFauyFTndOJkXPLNtPK7pGdVKrvqO6sWycpUl9drmbXH+iSbEBwCeYswPpT7Z6vrm+CZGet1voZXB2suzhUPjxZW4pG" ascii
    $s19 = "HCP6PBJZsrtexQbe+wBuRBTSnHBKxLAw5a2n2XasCEt2ak3F8euPG6t1d8xaVgkNV0CyucVxsPyBjKrqE7o89xou2IrxFSlBJkhdaKRBtwgLppDAn4etqDd2uHCF5vlx" ascii
    $s20 = "E6/htzyFgatgEtema9d9nYOWGlBjVxeC4+F9IwOkjx2zq8hAgVpgr8VBs2TrPZSbrWcYMiGRZHyjIjmiVcs2R/xZrs0kkYtTKTRwVjxY2olr2qHGfU32PMaQyQUhlDgW" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 600KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}