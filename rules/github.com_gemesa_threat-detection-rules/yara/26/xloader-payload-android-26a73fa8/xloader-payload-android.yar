rule xloader_payload_android {
  meta:
    description = "XLoader payload (Android)"
    author = "Andras Gemes"
    date = "2025-12-14"
    sha256 = "02c08ec2675abe6e09691419dd1a281194879c6e393de1cdfb150b864378d921"
    ref1 = "https://shadowshell.io/xloader"
    ref2 = "https://bazaar.abuse.ch/sample/02c08ec2675abe6e09691419dd1a281194879c6e393de1cdfb150b864378d921/"

  strings:
        
    $rpc0 = "sendSms"
    $rpc1 = "setWifi"
    $rpc2 = "gcont"
    $rpc3 = "lock"
    $rpc4 = "bc"
    $rpc5 = "setForward"
    $rpc6 = "getForward"
    $rpc7 = "hasPkg"
    $rpc8 = "setRingerMode"
    $rpc9 = "setRecEnable"
    $rpc10 = "reqState"
    $rpc11 = "showHome"
    $rpc12 = "getnpki"
    $rpc13 = "http"
    $rpc14 = "onRecordAction"
    $rpc15 = "call"
    $rpc16 = "get_apps"
    $rpc17 = "ping"
    $rpc18 = "getPhoneState"
    $rpc19 = "get_gallery"
    $rpc20 = "get_photo"

        $rpc21 = "on_call_rec"
    $rpc22 = "is_call_rec_enable"
    $rpc23 = "setMyInfo"
    $rpc24 = "setMyVCode"
    $rpc25 = "openbrowser2"

        $pinterest0 = "https://www.pinterest.com/emeraldquinn4090/"
    $pinterest1 ="https://www.pinterest.com/kelliemarshall9518/"
    $pinterest2 ="https://www.pinterest.com/shonabutler10541/"
    $pinterest3 ="https://www.pinterest.com/norahspencer9/"
    $pinterest4 ="https://www.pinterest.com/singletonabigail/"
    $pinterest5 ="https://www.pinterest.com/felicitynewman8858/"
    $pinterest6 ="https://www.pinterest.com/abigailn674/"
    $pinterest7 ="https://www.pinterest.com/gh6855786/"
    $pinterest8 ="https://www.pinterest.com/catogreggex11/"
    $pinterest9 ="https://www.pinterest.com/ingalcliffth/"
    $pinterest10 ="https://www.pinterest.com/husaincrisp/"

        $vk0 = "ffgtrrt([\\w_-]+?)ffgtrrt"
    $vk1 = "freefh([\\w_-]+?)freefh"
    $vk2 = "gfrtthnm([\\w_-]+?)gfrtthnm"
    $vk3 = "ohgftyn([\\w_-]+?)ohgftyn"
    $vk4 = "fdthjn([\\w_-]+?)fdthjn"
    $vk5 = "gftrtr([\\w_-]+?)gftrtr"
    $vk6 = "bgfrewi([\\w_-]+?)bgfrewi"
    $vk7 = "htynff([\\w_-]+?)htynff"
    $vk8 = "hfdrgf([\\w_-]+?)hfdrgf"
    $vk9 = "fdedsds([\\w_-]+?)fdedsds"
    $vk10 = "dsfewdw([\\w_-]+?)dsfewdw"
    $vk11 = "retredwcd([\\w_-]+?)retredwcd"

        $fs0 = "/NPKI"
    $fs1 = ".rec"
    $fs2 = ".rec.amr"

        $bank0 = "jp.co.smbc.direct"
    $bank1 = "jp.co.rakuten_bank.rakutenbank"
    $bank2 = "jp.mufg.bk.applisp.app"
    $bank3 = "jp.co.japannetbank.smtapp.balance"
    $bank4 = "jp.co.netbk.smartkey.SSNBSmartkey"
    $bank5 = "jp.japanpost.jp_bank.FIDOapp"
    $bank6 = "jp.co.jibunbank.jibunmain"
    $bank7 = "jp.co.sevenbank.AppPassbook"

            $field0 = "공인인증서" ascii wide
        $field1 = "비밀번호" ascii wide
        $field2 = "카드번호" ascii wide
        $field3 = "카드소유자명" ascii wide
        $field4 = "유효기간" ascii wide
        $field5 = "우편번호" ascii wide

  condition:
    20 of them
}