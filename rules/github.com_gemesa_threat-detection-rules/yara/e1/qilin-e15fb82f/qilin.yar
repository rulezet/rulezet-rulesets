import "elf"
rule qilin {
  meta:
    description = "Qilin"
    author = "Andras Gemes"
    date = "2025-03-12"
    sha256 = "555964b2fed3cced4c75a383dd4b3cf02776dae224f4848dcc03510b1de4dbf4"
    ref1 = "https://shadowshell.io/qilin-ransomware"
    ref2 = "https://bazaar.abuse.ch/sample/555964b2fed3cced4c75a383dd4b3cf02776dae224f4848dcc03510b1de4dbf4"

  strings:
    $1 = "Disables process kill"
    $2 = "Disables rename of completed files"
    $3 = "Disables snapshot deletion"
    $4 = "Disables VM kill"
    $5 = "for I in $(esxcli storage filesystem list |grep 'VMFS-5' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk > /dev/null; vmkfstools -U $I/eztDisk > /dev/null; done"
    $6 = "for I in $(esxcli storage filesystem list |grep 'VMFS-5' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk; vmkfstools -U $I/eztDisk; done"
    $7 = "for I in $(esxcli storage filesystem list |grep 'VMFS-6' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk > /dev/null; vmkfstools -U $I/eztDisk > /dev/null; done"
    $8 = "for I in $(esxcli storage filesystem list |grep 'VMFS-6' |awk '{print $1}'); do vmkfstools -c 10M -d eagerzeroedthick $I/eztDisk; vmkfstools -U $I/eztDisk; done"
    $9 = "esxcfg-advcfg -s 32768 /BufferCache/MaxCapacity"
    $10 = "esxcfg-advcfg -s 20000 /BufferCache/FlushInterval"
    $11 = "esxcli vm process list"
    $12 = "esxcli vm process kill -t force -w %llu"
    $13 = "vim-cmd vmsvc/getallvms"
    $14 = "vim-cmd vmsvc/snapshot.removeall %llu > /dev/null 2>&1"
    $15 = "dhl:p:Rrt:wy"
    $16 = "%s_RECOVER.txt"
    $17 = "/etc/motd.template"
    $18 = "/var/run/motd"
    $19 = "/etc/motd"
    $20 = "-----BEGIN PUBLIC KEY-----"
    $21 = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3a4G68kgJX2bwWZX23Yz\nzPI68Fl6eocJ+XLcPN9dvG3o/SV04F2zE7nWUhBbwsBHiX8bIquqVyVV+Y93FOCn\neJODySiy+bLZ1QfXKMjoNbhHq+aeuYCV8na3LF3hoGpST6uJpXUxbhZOBqHHbbx6\nvVy1fXOUEvaEOhqkglfDUQ7/fH6sT1p/3RyCtGi3o7588oMHOVgz3jZux2dqp9Zy\nPs9MqZs0OtcBAXTG4EmD8yz2RgH+D9j756snWNZeknnjNO+KUARDSICKFOYtb3wz\nxYFVvACB3sJuTpAJ2HuaWIEo8NljGsMkNTqy3tFY0WnUBxAgt7AMUM+Ex75DGa9H\nIAXd+bTOfo+zyUGKiUFBqBZjo8T0ueTpr8BZb98fl5/LFpXmBuR/dJBfeuq3a4vK\nFpxx796zUe/hoiBSvw9GzLyYa5A5Lbcz2qOi9RTYTEmZDX9qss+GfI54ZM2vrxyC\nnUJz/dDxxjFOujMJJBN9b1G9KIgiD3Sh41RLfEEemOG4Fo+1TbegKcK11a3LvUfL\ng3PhwflhaZwuwz3Nrie9vS9NKM+935rCkjeP1tap8NvrKow4F0KPg0loES06/fjm\n47PI12ZrUc6YE5zH3CwtiCXW4BUlpPacZgUJRpvZAODHYlejTnxtiWvq4XLe1A+3\n98/IXu0IMoFWAH2KnlPsczsCAwEAAQ==\n-----END PUBLIC KEY-----\n"
    $22 = "Detected OS: ESXi (%d)"
    $23 = "Are you sure to start encryption? (y/n)"
    $24 = "File tree traversing done. Waiting workers to complete..."
    $25 = "Qilin"
    $26 = "Your network/system was encrypted."
    $27 = "o7L03e8F9J"

  condition:
    defined(elf.type) and 15 of them
}